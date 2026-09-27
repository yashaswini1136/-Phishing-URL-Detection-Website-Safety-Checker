import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import MODEL_PATH, SCALER_PATH

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "domain_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "slash_count",
    "digit_count",
    "special_character_count",
    "digit_ratio",
    "special_char_ratio",
    "subdomain_count",
    "query_param_count",
    "path_depth",
    "hostname_entropy",
    "domain_entropy",
    "has_high_domain_entropy",
    "domain_hyphen_count",
    "domain_digit_count",
    "has_https",
    "has_http",
    "has_ip_address",
    "has_url_shortener",
    "has_at_symbol",
    "has_double_slash_path",
    "has_punycode",
    "has_percent_encoding",
    "has_suspicious_tld",
    "has_suspicious_port",
    "has_executable_extension",
    "has_redirect_params",
    "has_external_redirect_target",
    "is_brand_impersonation",
    "is_brand_authorized",
    "is_known_legitimate_domain",
    "is_contextually_suspicious",
    "suspicious_keyword_count",
    "has_login_keywords",
    "has_account_keywords",
    "has_payment_keywords",
]


def extract_feature_vector(features: Dict[str, Any]) -> List[float]:
    """
    Transforms extracted multi-layer URL features into a numeric vector
    compatible with scikit-learn models.
    """
    return [
        float(features.get("url_length", 0)),
        float(features.get("hostname_length", 0)),
        float(features.get("domain_length", 0)),
        float(features.get("path_length", 0)),
        float(features.get("query_length", 0)),
        float(features.get("dot_count", 0)),
        float(features.get("hyphen_count", 0)),
        float(features.get("underscore_count", 0)),
        float(features.get("slash_count", 0)),
        float(features.get("digit_count", 0)),
        float(features.get("special_character_count", 0)),
        float(features.get("digit_ratio", 0.0)),
        float(features.get("special_char_ratio", 0.0)),
        float(features.get("subdomain_count", 0)),
        float(features.get("query_param_count", 0)),
        float(features.get("path_depth", 0)),
        float(features.get("hostname_entropy", 0.0)),
        float(features.get("domain_entropy", 0.0)),
        1.0 if features.get("has_high_domain_entropy", False) else 0.0,
        float(features.get("domain_hyphen_count", 0)),
        float(features.get("domain_digit_count", 0)),
        1.0 if features.get("has_https", False) else 0.0,
        1.0 if features.get("has_http", False) else 0.0,
        1.0 if features.get("has_ip_address", False) else 0.0,
        1.0 if features.get("has_url_shortener", False) else 0.0,
        1.0 if features.get("has_at_symbol", False) else 0.0,
        1.0 if features.get("has_double_slash_path", False) else 0.0,
        1.0 if features.get("has_punycode", False) else 0.0,
        1.0 if features.get("has_percent_encoding", False) else 0.0,
        1.0 if features.get("has_suspicious_tld", False) else 0.0,
        1.0 if features.get("has_suspicious_port", False) else 0.0,
        1.0 if features.get("has_executable_extension", False) else 0.0,
        1.0 if features.get("has_redirect_params", False) else 0.0,
        1.0 if features.get("has_external_redirect_target", False) else 0.0,
        1.0 if features.get("is_brand_impersonation", False) else 0.0,
        1.0 if features.get("is_brand_authorized", False) else 0.0,
        1.0 if features.get("is_known_legitimate_domain", False) else 0.0,
        1.0 if features.get("is_contextually_suspicious", False) else 0.0,
        float(features.get("suspicious_keyword_count", 0)),
        1.0 if features.get("has_login_keywords", False) else 0.0,
        1.0 if features.get("has_account_keywords", False) else 0.0,
        1.0 if features.get("has_payment_keywords", False) else 0.0,
    ]


class URLClassifier:
    """
    Machine Learning Classifier for Phishing URL Analysis.
    Evaluates trained scikit-learn models (e.g. Random Forest, Logistic Regression)
    and supports graceful fallback to rule-based heuristics if no model is present.
    """
    def __init__(self):
        self.model = None
        self.scaler = None
        self.metadata = {}
        self.is_loaded = False
        self._load_model()

    def _load_model(self) -> None:
        if os.path.exists(MODEL_PATH):
            try:
                import joblib
                bundle = joblib.load(MODEL_PATH)
                if isinstance(bundle, dict):
                    self.model = bundle.get("model")
                    self.scaler = bundle.get("scaler")
                    self.metadata = bundle.get("metadata", {})
                else:
                    self.model = bundle
                self.is_loaded = self.model is not None
            except Exception as e:
                print(f"[Classifier] Failed to load trained model: {e}")
                self.is_loaded = False
        else:
            self.is_loaded = False

    def reload(self) -> bool:
        self._load_model()
        return self.is_loaded

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Runs ML prediction on extracted features.
        Returns prediction probability, classification verdict, and metadata.
        """
        if not self.is_loaded or self.model is None:
            return {
                "detection_method": "Rule-Based Heuristic Analysis",
                "ml_available": False,
                "ml_phishing_probability": None,
                "ml_prediction": None,
                "hybrid_confidence": None,
            }

        try:
            vec = [extract_feature_vector(features)]
            if self.scaler is not None:
                vec = self.scaler.transform(vec)

            # Predict probability
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(vec)[0]
                phishing_prob = round(float(probs[1]), 3)
            else:
                pred = int(self.model.predict(vec)[0])
                phishing_prob = 1.0 if pred == 1 else 0.0

            ml_prediction = "POTENTIAL_PHISHING" if phishing_prob >= 0.5 else "LEGITIMATE"

            return {
                "detection_method": "Hybrid Rule + ML Analysis",
                "ml_available": True,
                "ml_phishing_probability": phishing_prob,
                "ml_prediction": ml_prediction,
                "hybrid_confidence": f"{round(phishing_prob * 100, 1)}%",
                "model_type": self.metadata.get("algorithm", "RandomForestClassifier"),
            }
        except Exception as e:
            print(f"[Classifier] Error during inference: {e}")
            return {
                "detection_method": "Rule-Based Heuristic Analysis",
                "ml_available": False,
                "ml_phishing_probability": None,
                "ml_prediction": None,
                "hybrid_confidence": None,
            }


# Singleton instance
classifier_instance = URLClassifier()
