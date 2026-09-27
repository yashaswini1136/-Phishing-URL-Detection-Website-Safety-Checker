import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import DATABASE_PATH


def get_db_connection() -> sqlite3.Connection:
    Path(DATABASE_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            classification TEXT NOT NULL,
            indicator_count INTEGER NOT NULL,
            detection_method TEXT NOT NULL,
            features_json TEXT NOT NULL,
            indicators_json TEXT NOT NULL,
            recommendations_json TEXT NOT NULL,
            domain_analysis_json TEXT NOT NULL,
            confidence REAL DEFAULT 0.85,
            original_url TEXT DEFAULT ''
        )
    """)
    # Check if migration is needed for existing databases
    cursor.execute("PRAGMA table_info(scans)")
    columns = [col[1] for col in cursor.fetchall()]
    if "confidence" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN confidence REAL DEFAULT 0.85")
    if "original_url" not in columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN original_url TEXT DEFAULT ''")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans (classification)")
    conn.commit()
    conn.close()


def save_scan(data: Dict[str, Any]) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()

    now_iso = datetime.now(timezone.utc).isoformat()
    features_json = json.dumps(data.get("features", {}))
    indicators_json = json.dumps(data.get("indicators", []))
    recommendations_json = json.dumps(data.get("recommendations", []))
    domain_analysis_json = json.dumps(data.get("domain_analysis", {}))
    confidence_val = float(data.get("confidence", 0.85))
    orig_url = str(data.get("original_url", data["url"]))

    cursor.execute("""
        INSERT INTO scans (
            url, timestamp, risk_score, risk_level, classification,
            indicator_count, detection_method, features_json, indicators_json,
            recommendations_json, domain_analysis_json, confidence, original_url
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["url"],
        now_iso,
        int(data["risk_score"]),
        data["risk_level"],
        data["classification"],
        int(data["indicator_count"]),
        data.get("detection_method", "Rule-Based Heuristic Analysis"),
        features_json,
        indicators_json,
        recommendations_json,
        domain_analysis_json,
        confidence_val,
        orig_url
    ))
    conn.commit()
    scan_id = cursor.lastrowid or 0
    conn.close()
    return scan_id


def get_history(
    search: Optional[str] = None,
    classification: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Tuple[List[Dict[str, Any]], int]:
    conn = get_db_connection()
    cursor = conn.cursor()

    where_clauses = []
    params: List[Any] = []

    if search:
        where_clauses.append("(url LIKE ? OR original_url LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])

    if classification and classification.upper() != "ALL":
        target_class = classification.upper()
        if target_class in ("PHISHING", "POTENTIAL_PHISHING"):
            where_clauses.append("(classification = 'PHISHING' OR classification = 'POTENTIAL_PHISHING')")
        else:
            where_clauses.append("classification = ?")
            params.append(target_class)

    where_stmt = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

    # Get total matching count
    count_query = f"SELECT COUNT(*) FROM scans {where_stmt}"
    cursor.execute(count_query, params)
    total_count = cursor.fetchone()[0]

    # Query items
    items_query = f"""
        SELECT id, url, original_url, timestamp, risk_score, risk_level, classification,
               indicator_count, detection_method, confidence
        FROM scans
        {where_stmt}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """
    cursor.execute(items_query, params + [limit, offset])
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "url": r["url"],
            "original_url": r["original_url"] or r["url"],
            "timestamp": r["timestamp"],
            "risk_score": r["risk_score"],
            "risk_level": r["risk_level"],
            "classification": r["classification"],
            "indicator_count": r["indicator_count"],
            "detection_method": r["detection_method"],
            "confidence": round(float(r["confidence"] or 0.85), 2),
        })

    return results, total_count


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row["id"],
        "url": row["url"],
        "original_url": row["original_url"] or row["url"],
        "timestamp": row["timestamp"],
        "risk_score": row["risk_score"],
        "risk_level": row["risk_level"],
        "classification": row["classification"],
        "indicator_count": row["indicator_count"],
        "detection_method": row["detection_method"],
        "confidence": round(float(row["confidence"] or 0.85), 2),
        "features": json.loads(row["features_json"]),
        "indicators": json.loads(row["indicators_json"]),
        "recommendations": json.loads(row["recommendations_json"]),
        "domain_analysis": json.loads(row["domain_analysis_json"]),
    }


def delete_scan(scan_id: int) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def clear_all_scans() -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return True


def get_statistics() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification = 'SAFE'")
    safe_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification = 'SUSPICIOUS'")
    suspicious_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification IN ('PHISHING', 'POTENTIAL_PHISHING')")
    phishing_count = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(risk_score) FROM scans")
    avg_score_raw = cursor.fetchone()[0]
    avg_score = round(float(avg_score_raw), 1) if avg_score_raw is not None else 0.0

    # Detection rate: (Phishing + Suspicious) / Total * 100
    threat_count = suspicious_count + phishing_count
    detection_rate = round((threat_count / total_scans * 100), 1) if total_scans > 0 else 0.0

    # Top triggered indicators
    cursor.execute("SELECT indicators_json FROM scans ORDER BY id DESC LIMIT 100")
    indicator_rows = cursor.fetchall()
    conn.close()

    indicator_counts: Dict[str, int] = {}
    for (ind_str,) in indicator_rows:
        try:
            inds = json.loads(ind_str)
            for item in inds:
                name = item.get("name", "Unknown")
                indicator_counts[name] = indicator_counts.get(name, 0) + 1
        except Exception:
            pass

    top_indicators = [
        {"name": k, "count": v}
        for k, v in sorted(indicator_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]

    return {
        "total_scans": total_scans,
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "phishing_count": phishing_count,
        "detection_rate": detection_rate,
        "avg_risk_score": avg_score,
        "top_indicators": top_indicators,
    }
