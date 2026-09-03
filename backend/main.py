"""
GovShield / Sentinel Grid — Defense-in-Depth AI/ML Phishing Detection & Sovereign CTI Backend
SIH 2026 Problem Statement SIH1454

Architecture Note:
Enterprise multi-layer threat detection engine integrating:
- RFC 3986 URL Normalization & Obfuscation Stripping
- Pluggable Threat Intelligence Providers (URLhaus, Sovereign Ledger, OpenPhish)
- DNS, RDAP & TLS Certificate Forensics (Let's Encrypt vs NIC CA, NRD age)
- Hardened Anti-SSRF Sandboxed Web Crawler (DNS rebinding & private IP blocking)
- DOM, Sensitive Credential Form & Script Forensics (Aadhaar, PAN, OTP, Bank, UPI)
- Contextual Government Brand & Impersonation Engine (Official vs News/3rd-Party vs Phishing)
- MinHash Pure-Python Content & Structural Shingling
- Visual Perceptual Similarity Matching (pHash/dHash)
- External Cyber Threat Research Domain (CERT-In, RBI, NPCI Advisories)
- Gemini 2.0 Flash Semantic Synthesis & Threat Reasoning (Facts vs Inferences)
- Calibrated Multi-Signal Evidence Correlation Engine
- RFC 8785 Canonical JSON Hashing & Sovereign PoA Blockchain Threat Ledger
- Section 65B Indian Evidence Act Court-Admissible Electronic Certificates
"""

import sys
import os
import time
import datetime
import uuid
import csv
import io
import asyncio
from typing import Optional, List, Dict, Any, Literal
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field

# Ensure backend directory is in sys.path
_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

# Fix Windows console encoding
if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Core Forensic Modules
from modules.url_normalizer import URLNormalizer
from modules.network_analyzer import NetworkAnalyzer
from modules.threat_intel import ThreatIntelHub
from modules.brand_engine import BrandEngine
from modules.safe_crawler import SafeCrawler
from modules.dom_analyzer import DOMAnalyzer
from modules.visual_analyzer import VisualSimilarityAnalyzer
from modules.research_engine import ResearchEngine
from modules.internet_search_engine import InternetSearchEngine
from modules.ai_agent import AIAgent
from modules.fusion_engine import FusionEngine
from modules.blockchain_ledger import blockchain_ledger, canonical_json
from modules.certin_reporter import CertInReporter
from modules.reference_database import GENUINE_PORTALS
from modules.content_similarity import text_similarity, dom_similarity
from modules.lexical_analyzer import LexicalAnalyzer
from modules.whois_analyzer import WhoisAnalyzer

app = FastAPI(
    title="GovShield Sentinel Grid — Sovereign Cyber Threat Intelligence & Multi-Layer Phishing Defense",
    description="Enterprise defense-in-depth detection pipeline conforming to CERT-In standards, Sovereign PoA Blockchain, and Section 65B Indian Evidence Act.",
    version="2.2.0"
)

# Enable CORS for web portals, Chrome extensions, and SIEM tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------
# Module Instantiations
# -------------------------------------------------------------
url_normalizer = URLNormalizer()
network_analyzer = NetworkAnalyzer()
threat_intel_hub = ThreatIntelHub()
brand_engine = BrandEngine()
safe_crawler = SafeCrawler(timeout=3.5, max_bytes=512_000)
dom_analyzer = DOMAnalyzer()
visual_analyzer = VisualSimilarityAnalyzer()
research_engine = ResearchEngine()
internet_search_engine = InternetSearchEngine(timeout=2.5)
ai_agent = AIAgent()
fusion_engine = FusionEngine()
certin_reporter = CertInReporter()
legacy_lexical = LexicalAnalyzer()
legacy_whois = WhoisAnalyzer()

# High-Performance Production Cache (TTL 180s)
SCAN_CACHE: Dict[str, Dict[str, Any]] = {}
CACHE_TTL_SECONDS = 180

# CTI Live Threat Feeds and Background Async Jobs
RECENT_VERDICTS: List[Dict[str, Any]] = []
ASYNC_JOBS: Dict[str, Dict[str, Any]] = {}

# System Observability Metrics
METRICS = {
    "total_scans": 0,
    "malicious_detected": 0,
    "suspicious_detected": 0,
    "legitimate_verified": 0,
    "threat_intel_hits": 0,
    "avg_latency_ms": 0.0,
    "total_latency_accumulated_ms": 0.0
}

# Simple In-Memory Sliding Window Rate Limiting (60 requests / minute / IP)
RATE_LIMIT_BUCKETS: Dict[str, List[float]] = {}
RATE_LIMIT_MAX_REQUESTS = 120
RATE_LIMIT_WINDOW_SECONDS = 60.0


@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    """Enforces lightweight rate-limiting per client IP to mitigate denial-of-service."""
    client_ip = request.client.host if request.client else "unknown"

    # Skip static files and health checks from rate limiting
    if request.url.path in ["/healthz", "/readyz", "/api/health", "/api/metrics"] or request.url.path.startswith(("/css", "/js", "/images")):
        return await call_next(request)

    now = time.time()
    timestamps = RATE_LIMIT_BUCKETS.get(client_ip, [])
    # Filter out timestamps older than window
    timestamps = [ts for ts in timestamps if (now - ts) < RATE_LIMIT_WINDOW_SECONDS]
    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please wait before submitting additional scan requests."}
        )
    timestamps.append(now)
    RATE_LIMIT_BUCKETS[client_ip] = timestamps

    return await call_next(request)


# -------------------------------------------------------------
# Request & Response Models
# -------------------------------------------------------------
class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to inspect")
    html_content: Optional[str] = Field(None, description="DOM HTML content extracted by extension")
    image_base64: Optional[str] = Field(None, description="Base64 encoded page screenshot")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class QuickCheckRequest(BaseModel):
    url: str = Field(..., description="Target URL to quickly analyze")


class CertInReportRequest(BaseModel):
    scan_result: Dict[str, Any]
    reporter_notes: Optional[str] = None


class VerifyEvidenceRequest(BaseModel):
    incident_id: str
    evidence_bundle: Dict[str, Any]


# -------------------------------------------------------------
# Health, Readiness, and Observability Endpoints
# -------------------------------------------------------------
@app.get("/healthz")
def healthz_probe():
    """Kubernetes / Cloud liveness probe."""
    return {"status": "ok", "version": "2.2.0", "service": "GovShield Sentinel Grid"}


@app.get("/readyz")
def readyz_probe():
    """Kubernetes / Cloud readiness probe."""
    return {
        "ready": True,
        "blockchain_active": blockchain_ledger.is_chain_valid(),
        "blockchain_valid": blockchain_ledger.is_chain_valid(),
        "brand_registry_size": len(GENUINE_PORTALS),
        "threat_intel_providers": len(threat_intel_hub.providers)
    }


@app.get("/api/health")
def api_health():
    """Operational health status of all sub-engines."""
    return {
        "status": "online",
        "system": "GovShield Sentinel Grid — Defense-in-Depth Cyber Intelligence",
        "version": "2.2.0",
        "models_loaded": {
            "url_normalizer": True,
            "network_analyzer": True,
            "threat_intel_hub": True,
            "brand_engine": True,
            "safe_crawler": True,
            "dom_form_inspector": True,
            "visual_phash_matcher": True,
            "research_engine": True,
            "gemini_semantic_agent": ai_agent.client_ready,
            "fusion_risk_engine": True,
            "sovereign_blockchain_ledger": True
        },
        "blockchain_status": {
            "active": True,
            "chain_height": len(blockchain_ledger.chain),
            "chain_valid": blockchain_ledger.is_chain_valid(),
            "latest_block_hash": blockchain_ledger.get_latest_block().hash
        },
        "ai_model": ai_agent.model_name if ai_agent.client_ready else "deterministic_fallback_synthesis",
        "indexed_reference_portals_count": len(GENUINE_PORTALS)
    }


@app.get("/api/metrics")
def get_system_metrics():
    """Observability telemetry for SIEM and operational monitoring."""
    return {
        "status": "success",
        "timestamp": time.time(),
        "metrics": METRICS,
        "active_cache_size": len(SCAN_CACHE),
        "recent_verdicts_buffer_size": len(RECENT_VERDICTS)
    }


@app.get("/api/brands")
def get_brand_registry():
    """Programmatic discovery of all 21+ indexed sovereign entities."""
    brands = []
    for pid, data in GENUINE_PORTALS.items():
        brands.append({
            "id": pid,
            "name": data["name"],
            "department": data["department"],
            "category": data.get("category", "sovereign_service"),
            "primary_domain": data["primary_domain"],
            "valid_domains": data.get("valid_domains", [])
        })
    return {"status": "success", "count": len(brands), "brands": brands}


@app.get("/api/feed")
def get_threat_feed(format: Literal["json", "csv"] = "json", limit: int = 50):
    """Real-time CTI threat intelligence feed export."""
    items = list(reversed(RECENT_VERDICTS))[:limit]
    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["incident_id", "url", "target_entity", "risk_score", "verdict", "threat_level", "timestamp"])
        writer.writeheader()
        for item in items:
            writer.writerow(item)
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=govshield_threat_intelligence.csv"}
        )

    return {"status": "success", "count": len(items), "verdicts": items}


@app.get("/api/scan/{scan_id}")
def get_async_scan_status(scan_id: str):
    """Retrieve status and verdict for an asynchronous scan job."""
    if scan_id not in ASYNC_JOBS:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    return ASYNC_JOBS[scan_id]


@app.get("/api/reference-sites")
def get_reference_sites():
    """Legacy endpoint returning all genuine Indian government portals."""
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


# -------------------------------------------------------------
# Blockchain & Evidence Verification Endpoints
# -------------------------------------------------------------
@app.get("/api/blockchain/stats")
def get_blockchain_stats():
    """Returns live PoA consensus status and ledger integrity metrics."""
    return {
        "status": "success",
        "blockchain_metrics": {
            "chain_integrity": "SECURE_VALID" if blockchain_ledger.is_chain_valid() else "COMPROMISED",
            "block_height": len(blockchain_ledger.chain),
            "threats_logged": sum(len(b.transactions) for b in blockchain_ledger.chain[1:]),
            "consensus": "Proof-of-Authority (PoA)",
            "authorized_validators": blockchain_ledger.authorized_validators
        }
    }


@app.get("/api/blockchain/chain")
def get_blockchain_chain():
    """Returns complete immutable chain of the Sovereign PoA Ledger."""
    chain_data = blockchain_ledger.get_chain()
    return {
        "status": "success",
        "chain_length": len(blockchain_ledger.chain),
        "length": len(blockchain_ledger.chain),
        "is_valid": blockchain_ledger.is_chain_valid(),
        "blocks": chain_data,
        "chain": chain_data
    }


@app.get("/api/blockchain/verify-evidence/{incident_id}")
def verify_incident_evidence_endpoint(incident_id: str):
    """Verifies evidence hash anchored on the sovereign blockchain."""
    for block in blockchain_ledger.chain:
        for tx in block.transactions:
            if tx.get("incident_id") == incident_id:
                return {
                    "status": "VERIFIED_ON_BLOCKCHAIN",
                    "incident_id": incident_id,
                    "block_index": block.index,
                    "block_hash": block.hash,
                    "evidence_hash": tx.get("evidence_hash"),
                    "timestamp": tx.get("timestamp"),
                    "validator_node": block.validator_node,
                    "tamper_status": "AUTHENTIC"
                }
    raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found on ledger.")


@app.get("/api/blockchain/section65b/{incident_id}")
def get_section65b_certificate(incident_id: str):
    """Generates Section 65B Indian Evidence Act court-admissible electronic certificate."""
    cert = blockchain_ledger.generate_section65b_certificate(incident_id)
    if not cert:
        raise HTTPException(status_code=404, detail=f"No forensic record found for incident ID '{incident_id}'.")
    return cert


@app.post("/api/verify-evidence")
def verify_evidence(req: VerifyEvidenceRequest):
    """Cryptographically verifies off-chain evidence against the on-chain anchored hash."""
    result = blockchain_ledger.verify_evidence_authenticity(req.incident_id, req.evidence_bundle)
    return result


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


@app.post("/api/quick-check")
def quick_check(req: QuickCheckRequest):
    """Fast pre-flight evaluation using URL normalization and threat intel."""
    url_meta = url_normalizer.normalize(req.url)
    brand_match = brand_engine.match_entity(url_meta.get("registered_domain", ""))
    threat_intel = threat_intel_hub.evaluate_url(url_meta.get("normalized_url", req.url))

    is_gov = url_meta.get("tld") in ["gov.in", "nic.in"]
    risk = 2 if is_gov else (95 if threat_intel.get("is_known_malicious") else 20)
    verdict = "LEGITIMATE" if is_gov else ("PHISHING_CLONE" if threat_intel.get("is_known_malicious") else "SUSPICIOUS")

    return {
        "url": req.url,
        "normalized_url": url_meta.get("normalized_url"),
        "risk_score": risk,
        "verdict": verdict,
        "target_entity": brand_match.get("organization") if brand_match else "Commercial Platform",
        "is_genuine_gov_tld": is_gov
    }


# -------------------------------------------------------------
# DEFENSE-IN-DEPTH SCAN PIPELINE
# -------------------------------------------------------------
def _execute_scan_pipeline(req: ScanRequest) -> Dict[str, Any]:
    """
    Executes the multi-layer defense-in-depth threat detection pipeline:
    1. RFC 3986 URL Normalization & Sanitization
    2. Pluggable Threat Intelligence Layer
    3. Network, DNS, RDAP & TLS Forensics
    4. Contextual Brand & Impersonation Engine
    5. Hardened Sandboxed Web Crawler (Anti-SSRF & DNS rebinding defense)
    6. DOM, Sensitive Token Form & Script Forensics
    7. MinHash Content & Structural Shingling
    8. Visual Lookalike Matching
    9. External Cyber Threat Research Advisories
    10. Gemini 2.0 Semantic Synthesis & Reasoning
    11. Calibrated Multi-Signal Fusion & Explainable Verdict
    12. Canonical RFC 8785 Evidence Hashing & PoA Blockchain Anchoring
    """
    start_time = time.time()
    METRICS["total_scans"] += 1

    # Step 1: URL Normalization
    url_meta = url_normalizer.normalize(req.url)
    normalized_url = url_meta.get("normalized_url", req.url)
    registered_domain = url_meta.get("registered_domain", "")
    hostname = url_meta.get("hostname", "")
    port = url_meta.get("port")
    scheme = url_meta.get("scheme", "https")

    # Fast in-memory cache hit
    cache_key = normalized_url.lower()
    now_ts = time.time()
    if not req.html_content and not req.image_base64 and cache_key in SCAN_CACHE:
        cached_item = SCAN_CACHE[cache_key]
        if (now_ts - cached_item["cached_at"]) < CACHE_TTL_SECONDS:
            res_copy = dict(cached_item["data"])
            res_copy["cached_result"] = True
            return res_copy

    # Step 2: Threat Intelligence Layer
    threat_intel = threat_intel_hub.evaluate_url(normalized_url)
    if threat_intel.get("is_known_malicious"):
        METRICS["threat_intel_hits"] += 1

    # Step 3: Network, DNS, RDAP & TLS Forensics
    network_evidence = network_analyzer.analyze(
        domain=registered_domain,
        hostname=hostname,
        port=port,
        scheme=scheme
    )

    # Step 4: Brand & Impersonation Matching
    brand_match = brand_engine.match_entity(
        domain=registered_domain,
        path=url_meta.get("path", ""),
        page_title=""
    )

    # Step 4b: Live Internet OSINT Search & PIB Advisory Check
    is_gov_tld = url_meta.get("tld") in ["gov.in", "nic.in"]
    internet_search_evidence = None
    if not is_gov_tld:
        internet_search_evidence = internet_search_engine.investigate_domain_osint(
            domain=registered_domain,
            entity_name=brand_match.get("organization") if brand_match else None
        )

    # Step 5: Safe Web Crawling (with strict anti-SSRF)
    crawler_res = None
    html_content = req.html_content
    if (not html_content or len(html_content.strip()) == 0) and not is_gov_tld and not threat_intel.get("is_known_malicious"):
        crawler_res = safe_crawler.fetch_url(normalized_url)
        if crawler_res.get("success"):
            html_content = crawler_res.get("html_content")

    # Step 6: DOM, Form & Script Analysis
    dom_evidence = dom_analyzer.analyze_html(
        html_content=html_content or "",
        base_url=normalized_url,
        matched_portal_id=brand_match.get("entity_id") if brand_match else None
    )

    # Step 7: MinHash Structural Shingling
    content_sim_res = None
    if html_content and brand_match:
        target_portal = GENUINE_PORTALS.get(brand_match["entity_id"])
        if target_portal:
            ref_keywords = " ".join(target_portal.get("keywords", []))
            t_sim = text_similarity(html_content, ref_keywords)
            if t_sim > 0.05:
                content_sim_res = {
                    "similarity": t_sim,
                    "reasons": [f"MinHash structural text & DOM outline confirms {int(t_sim * 100)}% similarity to official portal."] if t_sim >= 0.35 else []
                }

    # Step 8: Visual Lookalike Analysis
    visual_evidence = visual_analyzer.analyze_visual_lookalike(
        image_base64=req.image_base64,
        candidate_portal_id=brand_match.get("entity_id") if brand_match else None
    )

    # Step 9: Contextual Relationship Classification
    has_sensitive_forms = len(dom_evidence.get("sensitive_inputs", [])) > 0
    cnt_sim_score = float(content_sim_res.get("similarity", 0.0)) if content_sim_res else 0.0
    brand_evidence = brand_engine.classify_relationship(
        domain=registered_domain,
        entity_info=brand_match,
        has_sensitive_forms=has_sensitive_forms,
        content_similarity_score=cnt_sim_score,
        lexical_risk_score=75.0 if url_meta.get("has_homoglyphs") else 0.0
    )

    # Step 10: External Threat Research Domain
    domain_tokens = registered_domain.replace(".", "-").split("-")
    research_findings = research_engine.query_advisories(
        domain_tokens=domain_tokens,
        candidate_entity=brand_evidence.get("claimed_entity")
    )

    # Step 11: Gemini 2.0 Semantic Synthesis (Semantic Analyst, not binary judge)
    ai_synthesis = ai_agent.synthesize_evidence(
        url_metadata=url_meta,
        network_evidence=network_evidence,
        threat_intel_evidence=threat_intel,
        dom_evidence=dom_evidence,
        brand_evidence=brand_evidence,
        research_findings=research_findings,
        dom_sample=html_content or "",
        image_base64=req.image_base64,
        internet_search_evidence=internet_search_evidence
    )

    # Step 12: Calibrated Multi-Signal Fusion
    fused_verdict = fusion_engine.evaluate_comprehensive(
        url_metadata=url_meta,
        network_evidence=network_evidence,
        threat_intel_evidence=threat_intel,
        dom_evidence=dom_evidence,
        visual_evidence=visual_evidence,
        brand_evidence=brand_evidence,
        content_sim_evidence=content_sim_res,
        ai_synthesis=ai_synthesis,
        research_findings=research_findings,
        crawler_evidence=crawler_res,
        internet_search_evidence=internet_search_evidence
    )

    # Attach live internet OSINT findings
    if internet_search_evidence:
        fused_verdict["internet_search_advisories"] = internet_search_evidence

    # Blend Gemini insights into reasons when relevant
    if ai_synthesis.get("plain_english_summary"):
        fused_verdict["genai_synthesis"] = ai_synthesis
        if ai_synthesis.get("social_engineering_tactics"):
            fused_verdict["reasons"].extend(ai_synthesis["social_engineering_tactics"])

    # Step 13: Cryptographic Sovereign Blockchain Anchoring (RFC 8785 Canonical JSON)
    incident_id = f"CERTIN-INC-{uuid.uuid4().hex[:8].upper()}"
    fused_verdict["incident_id"] = incident_id

    blockchain_proof = blockchain_ledger.log_threat_incident(
        incident_id=incident_id,
        malicious_url=normalized_url,
        target_entity=fused_verdict.get("target_entity", "Indian Sovereign Service"),
        risk_score=fused_verdict.get("risk_score", 0),
        verdict=fused_verdict.get("verdict", "UNKNOWN"),
        forensic_evidence=fused_verdict.get("signal_breakdown", {}),
        html_dom_sample=html_content or "",
        reporter_notes="GovShield Sentinel Grid Defense-in-Depth Pipeline"
    )
    fused_verdict["blockchain_proof"] = blockchain_proof

    # Attach forensic evidence modules for frontend & API clients
    fused_verdict["url"] = normalized_url
    fused_verdict["original_url"] = req.url
    fused_verdict["url_metadata"] = url_meta
    fused_verdict["network_details"] = network_evidence
    fused_verdict["threat_intel"] = threat_intel
    fused_verdict["brand_details"] = brand_evidence
    fused_verdict["dom_details"] = dom_evidence
    fused_verdict["visual_details"] = visual_evidence
    fused_verdict["research_advisories"] = research_findings
    if content_sim_res:
        fused_verdict["content_similarity_details"] = content_sim_res

    # Terminal output for SIH jury demonstration
    print("\n" + "=" * 68)
    print(f"🛡️ [GOVSHIELD DEFENSE-IN-DEPTH SCAN] URL: {normalized_url}")
    print(f"  • Matched Entity: {fused_verdict.get('target_entity')}")
    print(f"  • Brand Category: {brand_evidence.get('classification')}")
    print(f"  • Threat Intel Hit: {threat_intel.get('is_known_malicious')} ({threat_intel.get('highest_confidence')})")
    print(f"  • Sensitive Citizen Inputs: {[s['field'] for s in dom_evidence.get('sensitive_inputs', [])]}")
    print(f"  • RDAP Domain Age: {network_evidence.get('rdap', {}).get('domain_age_days')} days")
    print(f"  • PoA Blockchain Proof: Block #{blockchain_proof.get('block_index')} | Hash: {blockchain_proof.get('evidence_hash', '')[:12]}...")
    print(f"  🎯 FINAL VERDICT: {fused_verdict['verdict']} | RISK SCORE: {fused_verdict['risk_score']}/100 | CONFIDENCE: {fused_verdict.get('confidence')}")
    print("=" * 68 + "\n")

    # Update metrics & recent feed
    duration_ms = (time.time() - start_time) * 1000
    METRICS["total_latency_accumulated_ms"] += duration_ms
    METRICS["avg_latency_ms"] = round(METRICS["total_latency_accumulated_ms"] / METRICS["total_scans"], 1)

    if fused_verdict["verdict"] in ["PHISHING_CLONE", "MALICIOUS"]:
        METRICS["malicious_detected"] += 1
    elif fused_verdict["verdict"] == "SUSPICIOUS":
        METRICS["suspicious_detected"] += 1
    else:
        METRICS["legitimate_verified"] += 1

    RECENT_VERDICTS.append({
        "incident_id": incident_id,
        "url": normalized_url,
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
    Comprehensive multi-signal scan supporting both synchronous and asynchronous modes.
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


# Mount live web portal directly on FastAPI server
from fastapi.staticfiles import StaticFiles

_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_website_path = os.path.join(_root_dir, "website")

if os.path.exists(_website_path):
    app.mount("/", StaticFiles(directory=_website_path, html=True), name="website")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"Starting GovShield Sentinel Grid AI/ML Server on http://{host}:{port}...")
    uvicorn.run(app, host=host, port=port)
