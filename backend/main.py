import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Ensure backend directory is in python path
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from config import RULE_WEIGHTS
from database.database import (
    clear_all_scans,
    delete_scan,
    get_history,
    get_scan_by_id,
    get_statistics,
    init_db,
    save_scan,
)
from detection.classifier import classifier_instance
from detection.feature_extractor import extract_all_features, normalize_url
from detection.risk_engine import calculate_risk

# Safe Logging Configuration (does NOT log credentials, tokens, or cookies)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SafetyChecker] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("PhishingDetector")

# Initialize Database schema & migrations
init_db()

app = FastAPI(
    title="Phishing URL Detection & Website Safety Checker API",
    description="Educational Cybersecurity URL Pattern Analysis & Explainable Threat Detection Platform",
    version="2.0.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:4173",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="URL string to analyze")


class RuleResponse(BaseModel):
    rule_id: str
    name: str
    weight: int
    severity: str
    description: str


@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Phishing URL Detection API",
        "version": "2.0.0",
        "ml_model_loaded": classifier_instance.is_loaded,
        "detection_modes": ["Heuristic Rule Engine", "Random Forest ML Classifier"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/analyze")
def analyze_url_endpoint(payload: AnalyzeRequest):
    start_time = time.perf_counter()
    raw_input = payload.url.strip()

    # Layer 1: Normalization & Sanity Validation (SSRF Safe - zero network requests)
    original_url, normalized_url, is_valid, error_msg = normalize_url(raw_input)
    if not is_valid:
        logger.warning(f"Rejected invalid URL input: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg or "Invalid URL input"
        )

    # Layer 2-5: Comprehensive Multi-Layer Feature Extraction
    features = extract_all_features(normalized_url, original_url=original_url)

    # Layer 7: Machine Learning Classifier Inference (if model loaded)
    ml_result = classifier_instance.predict(features=features)

    # Layer 6 & 8: Rule-Based Scoring, Evidence Fusion, and Confidence Calibration
    risk_evaluation = calculate_risk(features=features, ml_result=ml_result)

    processing_ms = round((time.perf_counter() - start_time) * 1000, 2)

    # Safe telemetry logging (Logs metrics & domain structure without sensitive tokens/passwords)
    hostname_logged = features.get("domain_analysis", {}).get("hostname", "unknown")
    logger.info(
        f"Analyzed host='{hostname_logged}' | score={risk_evaluation['risk_score']} | "
        f"verdict='{risk_evaluation['classification']}' | confidence={risk_evaluation['confidence']} | "
        f"indicators={risk_evaluation['indicator_count']} | duration={processing_ms}ms"
    )

    # Structure complete API response
    result_data = {
        "original_url": original_url,
        "normalized_url": normalized_url,
        "url": normalized_url,
        "classification": risk_evaluation["classification"],
        "risk_score": risk_evaluation["risk_score"],
        "confidence": risk_evaluation["confidence"],
        "risk_level": risk_evaluation["risk_level"],
        "detection_method": risk_evaluation["detection_method"],
        "indicator_count": risk_evaluation["indicator_count"],
        "indicators": risk_evaluation["indicators"],
        "legitimacy_credits": risk_evaluation["legitimacy_credits"],
        "recommendations": risk_evaluation["recommendations"],
        "features": features,
        "domain_analysis": features.get("domain_analysis", {}),
        "ml_metadata": ml_result,
        "processing_time_ms": processing_ms,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "disclaimer": risk_evaluation["disclaimer"],
    }

    # Save evaluation audit log into SQLite
    scan_id = save_scan(result_data)
    result_data["id"] = scan_id

    return result_data


@app.get("/api/history")
def get_history_endpoint(
    search: Optional[str] = Query(None, description="Search keyword in URL"),
    classification: Optional[str] = Query(None, description="Filter by classification (SAFE, SUSPICIOUS, POTENTIAL_PHISHING, PHISHING, ALL)"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    items, total = get_history(
        search=search,
        classification=classification,
        limit=limit,
        offset=offset
    )
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/history/{scan_id}")
def get_scan_detail_endpoint(scan_id: int):
    record = get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID #{scan_id} not found"
        )
    return record


@app.delete("/api/history/{scan_id}")
def delete_scan_endpoint(scan_id: int):
    success = delete_scan(scan_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID #{scan_id} not found"
        )
    return {"message": f"Scan #{scan_id} deleted successfully"}


@app.delete("/api/history")
def clear_all_history_endpoint():
    clear_all_scans()
    return {"message": "All scan history records cleared"}


@app.get("/api/statistics")
def get_statistics_endpoint():
    stats = get_statistics()
    return stats


@app.get("/api/rules", response_model=List[RuleResponse])
def get_rules_endpoint():
    rules_list = []
    for rule_id, rule_info in RULE_WEIGHTS.items():
        rules_list.append(RuleResponse(
            rule_id=rule_id,
            name=rule_info["name"],
            weight=rule_info["weight"],
            severity=rule_info["severity"],
            description=rule_info["description"]
        ))
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rules_list.sort(key=lambda r: (severity_order.get(r.severity, 99), -r.weight))
    return rules_list
