from typing import Any, Dict, List, Optional
from config import (
    LEGITIMACY_CREDITS,
    ML_WEIGHT,
    PHISHING_THRESHOLD,
    RISK_THRESHOLDS,
    RULE_WEIGHT,
    SAFE_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
)
from detection.rules import get_all_rules

MANDATORY_DISCLAIMER = (
    "Pattern-based detection cannot guarantee that a website is safe or malicious. "
    "A URL classified as Safe may still be compromised or malicious. "
    "Always verify the website and source independently."
)


def calculate_risk(
    features: Dict[str, Any],
    ml_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Evaluates heuristic detection rules, checks positive legitimacy evidence,
    fuses ML prediction probabilities when available, calculates calibrated confidence,
    and returns an explainable security verdict.
    """
    rules = get_all_rules()
    evaluated_indicators: List[Dict[str, Any]] = []
    positive_score = 0

    # 1. Evaluate Rule-Based Threat Indicators
    for rule in rules:
        res = rule.evaluate(features)
        if res["triggered"]:
            positive_score += res["score"]
            evaluated_indicators.append(res)

    # 2. Evaluate Positive Legitimacy Evidence (Negative Weights / Deductions)
    legitimacy_credits = 0
    legitimacy_notes = []

    # Verified Brand / Known Legitimate Domain Credit
    if features.get("is_brand_authorized") or features.get("is_known_legitimate_domain"):
        cred = LEGITIMACY_CREDITS["verified_brand_domain"]
        legitimacy_credits += cred["credit"]
        legitimacy_notes.append({
            "type": "LEGITIMACY_CREDIT",
            "name": "Verified Brand / Reputable Domain",
            "adjustment": cred["credit"],
            "reason": cred["reason"]
        })

    # Clean Structure Credit (no evasion, standard port, low entropy, normal length)
    is_clean = (
        not features.get("has_ip_address")
        and not features.get("has_at_symbol")
        and not features.get("has_punycode")
        and not features.get("has_url_shortener")
        and not features.get("is_brand_impersonation")
        and not features.get("has_suspicious_port")
        and not features.get("has_high_domain_entropy")
        and features.get("url_length", 0) <= 65
    )
    if is_clean and positive_score <= 15:
        cred = LEGITIMACY_CREDITS["clean_registered_structure"]
        legitimacy_credits += cred["credit"]
        legitimacy_notes.append({
            "type": "LEGITIMACY_CREDIT",
            "name": "Clean Heuristic Profile",
            "adjustment": cred["credit"],
            "reason": cred["reason"]
        })

    # Net Rule Score
    net_rule_score = max(0, min(100, positive_score + legitimacy_credits))

    # 3. Hybrid Score Fusion with Machine Learning
    ml_available = ml_result is not None and ml_result.get("ml_available", False)
    ml_prob = ml_result.get("ml_phishing_probability") if ml_available else None

    if ml_available and ml_prob is not None:
        ml_score = ml_prob * 100
        combined_score = round(RULE_WEIGHT * net_rule_score + ML_WEIGHT * ml_score)

        # Safety Guards:
        # If severe indicators exist (Brand Impersonation, Raw IP, @ symbol, Executable),
        # ML cannot suppress risk below SUSPICIOUS (minimum 45)
        has_severe_indicator = (
            features.get("is_brand_impersonation")
            or features.get("has_ip_address")
            or features.get("has_at_symbol")
            or features.get("has_executable_extension")
        )
        if has_severe_indicator:
            combined_score = max(combined_score, 50)

        # If verified reputable domain, ML cannot falsely flag standard login/auth paths
        if features.get("is_brand_authorized") or features.get("is_known_legitimate_domain"):
            if not has_severe_indicator:
                combined_score = min(combined_score, 20)

        final_risk_score = min(100, max(0, combined_score))
        detection_method = "Hybrid Rule + ML Analysis"
    else:
        final_risk_score = net_rule_score
        detection_method = "Rule-Based Heuristic Analysis"

    # 4. Risk Level Mapping
    if final_risk_score <= SAFE_THRESHOLD:
        risk_level = "LOW"
    elif final_risk_score <= SUSPICIOUS_THRESHOLD:
        risk_level = "MEDIUM"
    elif final_risk_score <= 79:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    # 5. Final Classification (POTENTIAL_PHISHING, SUSPICIOUS, SAFE)
    if final_risk_score <= SAFE_THRESHOLD:
        classification = "SAFE"
    elif final_risk_score <= SUSPICIOUS_THRESHOLD:
        classification = "SUSPICIOUS"
    else:
        classification = "POTENTIAL_PHISHING"

    # 6. Calibrated Confidence Calculation
    confidence = calculate_confidence(final_risk_score, evaluated_indicators, ml_prob, features)

    # Sort indicators by severity: HIGH -> MEDIUM -> LOW
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    evaluated_indicators.sort(
        key=lambda x: (severity_order.get(x["severity"], 99), -x["score"])
    )

    # 7. Security Recommendations
    recommendations = generate_recommendations(features, evaluated_indicators, classification)

    return {
        "risk_score": final_risk_score,
        "rule_risk_score": net_rule_score,
        "risk_level": risk_level,
        "classification": classification,
        "confidence": confidence,
        "detection_method": detection_method,
        "indicator_count": len(evaluated_indicators),
        "indicators": evaluated_indicators,
        "legitimacy_credits": legitimacy_notes,
        "recommendations": recommendations,
        "disclaimer": MANDATORY_DISCLAIMER
    }


def calculate_confidence(
    score: int,
    indicators: List[Dict[str, Any]],
    ml_prob: Optional[float],
    features: Dict[str, Any]
) -> float:
    """
    Computes a normalized confidence level (0.50 to 0.99) reflecting
    the strength, depth, and consistency of detected evidence.
    """
    # For high-threat phishing cases (score >= 60)
    if score >= 60:
        high_severity_count = sum(1 for ind in indicators if ind.get("severity") in ("HIGH", "CRITICAL"))
        if high_severity_count >= 2:
            return 0.96
        elif len(indicators) >= 2 or score >= 70:
            return 0.92
        return 0.88

    # For clear legitimate / safe cases (score <= 29)
    if score <= 29:
        if features.get("is_brand_authorized") or features.get("is_known_legitimate_domain"):
            return 0.98
        if len(indicators) == 0:
            return 0.94
        return 0.88

    # Borderline / Suspicious cases (30 <= score <= 59)
    if 30 <= score <= 59:
        if ml_prob is not None:
            agreement = 0.55 + abs(ml_prob - 0.50) * 0.4
            return round(min(0.85, max(0.55, agreement)), 2)
        return 0.70

    return 0.80


def generate_recommendations(
    features: Dict[str, Any],
    indicators: List[Dict[str, Any]],
    classification: str
) -> List[str]:
    recs: List[str] = []
    indicator_ids = {ind["rule_id"] for ind in indicators}

    if "brand_impersonation" in indicator_ids:
        brand = features.get("detected_brand", "target brand")
        recs.append(
            f"Brand Impersonation Warning: This domain appears to mimic {brand.title()} on an unauthorized host. Do not enter credentials."
        )

    if "ip_address" in indicator_ids:
        recs.append(
            "Verify the destination host before proceeding. Legitimate organizations host services on registered domain names, not raw IP addresses."
        )

    if "at_symbol" in indicator_ids:
        recs.append(
            "Extreme caution advised: The '@' symbol redirects your browser past the visible text to an obscured destination server."
        )

    if "punycode_homoglyph" in indicator_ids:
        recs.append(
            "Visual spoofing alert: This domain uses Punycode (IDN). The letters may resemble a well-known brand but use lookalike Cyrillic or foreign characters."
        )

    if "executable_download" in indicator_ids:
        recs.append(
            "Payload Warning: URL targets an executable file. Do NOT download or execute files from unsolicited links."
        )

    if "open_redirect_param" in indicator_ids:
        recs.append(
            "Open Redirect Alert: URL parameters route to an external website. Ensure the final destination is authentic."
        )

    if "http_unencrypted" in indicator_ids:
        recs.append(
            "Unencrypted Connection: Website uses plain HTTP without TLS. Any submitted passwords, tokens, or personal data can be intercepted."
        )

    if "url_shortener" in indicator_ids:
        recs.append(
            "Shortened Link: The authentic destination is concealed behind a URL shortener. Expand the link using an unshortener tool before visiting."
        )

    if "contextual_keywords" in indicator_ids:
        recs.append(
            "Credential Harvesting Alert: Sensitive authentication terms detected on an unverified domain. Never submit credentials unless domain is verified."
        )

    if classification == "POTENTIAL_PHISHING":
        recs.insert(
            0,
            "Potential Phishing Alert: High threat indicators detected. Do not enter passwords, banking details, OTPs, or personal identity information on this website."
        )
    elif classification == "SUSPICIOUS":
        recs.insert(
            0,
            "Suspicious URL: Multiple anomalous indicators observed. Inspect the domain carefully and verify the source through independent channels."
        )
    else:
        recs.append(
            "No prominent phishing indicators were detected by this pattern analyzer. This does not guarantee that the destination is completely safe."
        )

    # Mandatory educational disclaimer is always attached
    recs.append(MANDATORY_DISCLAIMER)

    return recs
