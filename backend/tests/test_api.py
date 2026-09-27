import pytest
from fastapi.testclient import TestClient
import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "service" in data
    assert data["ml_model_loaded"] is True


def test_analyze_legitimate_url():
    response = client.post("/api/analyze", json={"url": "https://github.com/login"})
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "SAFE"
    assert data["risk_score"] < 25
    assert "confidence" in data
    assert data["confidence"] > 0.80
    assert "original_url" in data
    assert "normalized_url" in data
    assert "detection_method" in data
    assert "features" in data
    assert "domain_analysis" in data
    assert "recommendations" in data
    assert "id" in data


def test_analyze_phishing_url_brand_impersonation():
    response = client.post(
        "/api/analyze",
        json={"url": "https://paypal.com.verify-account-center.xyz/login"}
    )
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "POTENTIAL_PHISHING"
    assert data["risk_score"] >= 60
    assert data["confidence"] >= 0.85
    assert data["indicator_count"] >= 2
    rule_ids = [ind["rule_id"] for ind in data["indicators"]]
    assert "brand_impersonation" in rule_ids


def test_analyze_malformed_url_validation():
    # URL with space
    res1 = client.post("/api/analyze", json={"url": "https://invalid url with spaces.com"})
    assert res1.status_code == 400
    assert "spaces" in res1.json()["detail"].lower()

    # Empty string
    res2 = client.post("/api/analyze", json={"url": "   "})
    assert res2.status_code == 400


def test_get_rules_endpoint():
    response = client.get("/api/rules")
    assert response.status_code == 200
    rules = response.json()
    assert len(rules) >= 15
    rule_ids = [r["rule_id"] for r in rules]
    assert "brand_impersonation" in rule_ids
    assert "domain_entropy_anomaly" in rule_ids
    assert "executable_download" in rule_ids


def test_history_and_statistics_flow():
    # Analyze a test URL
    res = client.post("/api/analyze", json={"url": "https://python.org/doc/test"})
    assert res.status_code == 200
    scan_id = res.json()["id"]

    # History retrieval
    hist_res = client.get("/api/history?search=python.org")
    assert hist_res.status_code == 200
    history = hist_res.json()
    assert history["total"] >= 1
    assert any(item["id"] == scan_id for item in history["items"])

    # Detail by ID
    detail_res = client.get(f"/api/history/{scan_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == scan_id
    assert "confidence" in detail

    # Statistics
    stats_res = client.get("/api/statistics")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_scans"] >= 1

    # Clean up single record
    del_res = client.delete(f"/api/history/{scan_id}")
    assert del_res.status_code == 200
